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

#include "bms_param.h"

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string BMS_PARAM_TABLE = "bms_param";
}
BmsParam::BmsParam()
{
    APP_LOGI("instance:%{private}p is created", this);
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = Constants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = BMS_PARAM_TABLE;
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
}

BmsParam::~BmsParam()
{
    APP_LOGI("instance:%{private}p is destroyed", this);
}

bool BmsParam::SaveParam(const std::string &key, const std::string &value)
{
    if (key.empty() || value.empty()) {
        APP_LOGE("key or value is empty.");
        return false;
    }

    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    return rdbDataManager_->InsertData(key, value);
}

bool BmsParam::GetParam(const std::string &key, std::string &value)
{
    if (key.empty()) {
        APP_LOGE("key is empty.");
        return false;
    }

    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    return rdbDataManager_->QueryData(key, value);
}

bool BmsParam::DeleteParam(const std::string &key)
{
    if (key.empty()) {
        APP_LOGE("key is empty.");
        return false;
    }

    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    return rdbDataManager_->DeleteData(key);
}
}  // namespace AppExecFwk
}  // namespace OHOS