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

#include "bms_param.h"

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
static std::map<std::string, std::string> BMS_PARAM;

BmsParam::BmsParam()
{
    APP_LOGD("BmsParam instance is created");
}

BmsParam::~BmsParam()
{
    APP_LOGD("BmsParam instance is destroyed");
}

bool BmsParam::GetBmsParam(const std::string &key, std::string &value)
{
    if (key.empty()) {
        APP_LOGE("key is empty");
        return false;
    }

    auto iter = BMS_PARAM.find(key);
    if (iter == BMS_PARAM.end()) {
        return false;
    }

    value = iter->second;
    return true;
}

bool BmsParam::SaveBmsParam(const std::string &paramKeyInfo, const std::string &paramValueInfo)
{
    if (paramKeyInfo.empty()) {
        APP_LOGE("key is empty");
        return false;
    }

    BMS_PARAM[paramKeyInfo] = paramValueInfo;
    return true;
}

bool BmsParam::DeleteBmsParam(const std::string &key)
{
    if (key.empty()) {
        APP_LOGE("key is empty");
        return false;
    }

    BMS_PARAM.erase(key);
    return true;
}

}  // namespace AppExecFwk
}  // namespace OHOS