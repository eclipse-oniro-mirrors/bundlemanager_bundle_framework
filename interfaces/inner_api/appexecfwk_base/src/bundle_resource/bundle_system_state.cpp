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

#include "bundle_system_state.h"

#include "nlohmann/json.hpp"
#include "json_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* JSON_KEY_COLOR_MODE = "colorMode";
const char* JSON_KEY_LANGUAGE = "language";
}

BundleSystemState::BundleSystemState()
{}

BundleSystemState::~BundleSystemState()
{}

BundleSystemState &BundleSystemState::GetInstance()
{
    static BundleSystemState bundleSystemState;
    return bundleSystemState;
}

void BundleSystemState::SetSystemLanguage(const std::string &language)
{
    std::unique_lock<std::shared_mutex> stateLock(stateMutex_);
    language_ = language;
}

std::string BundleSystemState::GetSystemLanguage()
{
    std::shared_lock<std::shared_mutex> stateLock(stateMutex_);
    return language_;
}

void BundleSystemState::SetSystemColorMode(const std::string &colorMode)
{
    std::unique_lock<std::shared_mutex> stateLock(stateMutex_);
    colorMode_ = colorMode;
}

std::string BundleSystemState::GetSystemColorMode()
{
    std::shared_lock<std::shared_mutex> stateLock(stateMutex_);
    return colorMode_;
}

std::string BundleSystemState::ToString()
{
    std::shared_lock<std::shared_mutex> stateLock(stateMutex_);
    nlohmann::json jsonObject = nlohmann::json {
        {JSON_KEY_COLOR_MODE, colorMode_},
        {JSON_KEY_LANGUAGE, language_}
    };
    try {
        return jsonObject.dump();
    } catch (const nlohmann::json::type_error &e) {
        APP_LOGE("json dump failed: %{public}s", e.what());
        return "";
    }
}

bool BundleSystemState::FromString(const std::string &systemState)
{
    nlohmann::json jsonObject = nlohmann::json::parse(systemState, nullptr, false);
    if (jsonObject.is_discarded()) {
        APP_LOGE("failed parse SystemState: %{public}s", systemState.c_str());
        return false;
    }
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    std::unique_lock<std::shared_mutex> stateLock(stateMutex_);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_COLOR_MODE,
        colorMode_,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_LANGUAGE,
        language_,
        false,
        parseResult);
    if (parseResult != ERR_OK) {
        APP_LOGE("read systemState jsonObject error : %{public}d", parseResult);
        return false;
    }
    return true;
}
} // AppExecFwk
} // OHOS
